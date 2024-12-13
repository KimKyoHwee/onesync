package com.intern.onesync.util;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ClientSettingsMixin {
    @JsonCreator
    public ClientSettingsMixin(
            @JsonProperty("requireProofKey") boolean requireProofKey,
            @JsonProperty("requireAuthorizationConsent") boolean requireAuthorizationConsent) {
    }
}

