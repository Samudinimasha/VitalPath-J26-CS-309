
CLINICAL_ROLES = {
    "DOCTOR", "NURSE", "SPECIALIST", "PARAMEDIC"
}

EMERGENCY_ROLES = {"DOCTOR", "SPECIALIST"}


def evaluate_policy(user, case, assigned, request, score):
    reasons = []

    # Hard-deny conditions override the weighted score.
    if not case.active:
        return "DENY", ["Emergency case is inactive"]

    if user.role not in CLINICAL_ROLES:
        return "DENY", ["Role is not authorized for clinical telemetry"]

    if request.purpose == "ADMINISTRATION":
        return "DENY", ["Administrative purpose cannot access telemetry"]

    if request.access_device != user.registered_device:
        return "DENY", ["Unregistered access endpoint"]

    # Emergency override is only a request at this stage.
    # No telemetry access is granted here.
    if request.purpose == "EMERGENCY" and not assigned:
        if (
            user.role in EMERGENCY_ROLES
            and case.severity == "CRITICAL"
            and user.on_shift
            and user.location == "HOSPITAL"
        ):
            return "BREAK_GLASS_REQUIRED", [
                "Eligible emergency request",
                "Justification and approval workflow required",
            ]

        return "DENY", [
            "Emergency override eligibility conditions not met"
        ]

    if not assigned:
        return "DENY", ["User is not assigned to this case"]

    if not user.on_shift:
        return "DENY", ["User is currently off shift"]

    if user.location != "HOSPITAL":
        return "DENY", ["Access location not permitted"]

    if score <= 0.20:
        return "ALLOW", ["Access policy satisfied"]

    if score <= 0.40:
        return "LIMITED_ACCESS", [
            "Additional contextual restrictions apply"
        ]

    return "DENY", ["Access risk exceeds allowed threshold"]
