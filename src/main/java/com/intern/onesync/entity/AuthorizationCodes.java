package com.intern.onesync.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class AuthorizationCodes {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "auth_code_id")
    private Long id;

    //TODO: 세미콜론으로 구분, ex) EMAIL;PROFILE
    @Column(name="auth_code_scope")
    private String scope;

    @Column(name="auth_code_expire")
    private LocalDateTime expire;

    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "auth_code_clients", referencedColumnName = "client_id")
    private Client clients;
}
