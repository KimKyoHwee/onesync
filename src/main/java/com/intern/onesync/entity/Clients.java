package com.intern.onesync.entity;

import enums.LogActionTypes;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@Table
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Clients {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "client_id")
    private Long id;

    @Column(name = "client_secret")
    private String secret;

    @Column(name="client_redirect_uri")
    private String uri;

    @Column(name="client_permit_scope")
    private LogActionTypes scope;

}
