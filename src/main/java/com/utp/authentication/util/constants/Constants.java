package com.utp.authentication.util.constants;

import lombok.experimental.UtilityClass;

@UtilityClass
public class Constants {
    public static final String ERROR_VALUE = "error";
    public static final String VALID_VALUE = "valid";

    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_USER_ID = "userId";
    public static final String SERVICE_SUBJECT = "authentication-service";
    public static final String ROLE_INTERNAL_SERVICE = "ROLE_INTERNAL_SERVICE";
    public static final long SERVICE_TOKEN_TTL_SECONDS = 60L;
}
