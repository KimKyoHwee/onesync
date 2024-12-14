package com.intern.onesync.controller;

import com.intern.onesync.dto.BasicJoinDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Slf4j
@Controller
public class AuthController {

    @Operation(summary = "로그인")
    @ApiResponse(responseCode = "201", description = "로그인 완료")
    @GetMapping("/login")
    public String login() {
        return "login";
    }



}