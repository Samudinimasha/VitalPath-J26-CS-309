
# Initial experimental weights.
# These are provisional, not clinically validated.

WEIGHTS = {
    "role": 0.20,
    "case": 0.20,
    "shift": 0.15,
    "location": 0.15,
    "device": 0.10,
    "purpose": 0.10,
    "emergency": 0.05,
    "behaviour": 0.05,
}

CLINICAL_ROLES = {
    "DOCTOR", "NURSE", "SPECIALIST", "PARAMEDIC"
}


def calculate_ars(user, case, assigned, request):
    factors = {
        "role": (
            0.0 if user.role in CLINICAL_ROLES else 1.0
        ),
        "case": 0.0 if assigned else 1.0,
        "shift": 0.0 if user.on_shift else 1.0,
        "location": (
            0.0 if user.location == "HOSPITAL" else 1.0
        ),
        "device": (
            0.0
            if request.access_device == user.registered_device
            else 1.0
        ),
        "purpose": (
            0.0
            if request.purpose in {
                "TREATMENT", "CONSULTATION", "EMERGENCY"
            }
            else 1.0
        ),
        "emergency": (
            0.0
            if request.purpose != "EMERGENCY"
            or case.severity == "CRITICAL"
            else 1.0
        ),
        # Placeholder until historical behaviour is implemented.
        "behaviour": 0.0,
    }

    score = sum(
        WEIGHTS[name] * value
        for name, value in factors.items()
    )

    return round(score, 3), factors
