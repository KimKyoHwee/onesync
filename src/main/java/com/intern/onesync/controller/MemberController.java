package com.intern.onesync.controller;

import com.intern.onesync.dto.BasicJoinDto;
import com.intern.onesync.service.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/member")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @Operation(summary = "회원가입")
    @ApiResponse(responseCode = "201", description = "회원가입완료")
    @PostMapping("/join")
    public ResponseEntity<Long> join(@RequestBody BasicJoinDto basicJoinDto) {
        return ResponseEntity.ok(memberService.saveMember(basicJoinDto));
    }
}
