package com.intern.onesync.util;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class TokenSettingsMixin {
    @JsonCreator
    public TokenSettingsMixin(
            @JsonProperty("accessTokenTimeToLive") java.time.Duration accessTokenTimeToLive,
            @JsonProperty("refreshTokenTimeToLive") java.time.Duration refreshTokenTimeToLive
    ) {
    }
}

