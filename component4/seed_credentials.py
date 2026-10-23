
import getpass

from sqlalchemy import select

from app.database import Base, engine, SessionLocal
from app.models import User, UserCredential
from app.services.authentication import hash_password


def main():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        users = db.scalars(select(User)).all()

        if not users:
            print("No hospital users found.")
            print("Start the FastAPI server first.")
            return

        for user in users:
            existing = db.get(UserCredential, user.id)

            if existing:
                print(f"Credentials already exist: {user.id}")
                continue

            password = getpass.getpass(
                f"Enter password for {user.id} ({user.role}): "
            )

            if len(password) < 12:
                print("Password must contain at least 12 characters.")
                print(f"Skipping {user.id}")
                continue

            credential = UserCredential(
                user_id=user.id,
                password_hash=hash_password(password),
                active=True,
            )

            db.add(credential)
            print(f"Credentials created for {user.id}")

        db.commit()
        print("\nCredential setup completed.")


if __name__ == "__main__":
    main()
