class ProvisioningError(Exception):
    code = "provisioning_error"
    status_code = 400


class ConflictError(ProvisioningError):
    code = "conflict"
    status_code = 409


class DependencyUnavailable(ProvisioningError):
    code = "dependency_unavailable"
    status_code = 503


class DisabledFeatureError(ProvisioningError):
    code = "live_provisioning_disabled"
    status_code = 503


class RateLimitError(ProvisioningError):
    code = "rate_limited"
    status_code = 429
