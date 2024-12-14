package com.intern.onesync.controller;

import com.intern.onesync.dto.BasicJoinDto;
import com.intern.onesync.dto.CreateClientDto;
import com.intern.onesync.service.ClientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/client")
@RequiredArgsConstructor
public class ClientController {
    private final ClientService clientService;

    @Operation(summary = "Client 객체 생성")
    @ApiResponse(responseCode = "200", description = "Client 저장 완료, ClientSecret 반환")
    @PostMapping("/save")
    public ResponseEntity<String> join(@RequestBody CreateClientDto createClientDto) {
        return ResponseEntity.ok(clientService.saveClient(createClientDto));
    }
}
