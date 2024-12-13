package com.intern.onesync.entity;

import enums.LogActionTypes;
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
public class Logs {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "log_id")
    private Long id;

    @Column(name = "log_action")
    private LogActionTypes action;

    @Column(name="log_timestamp")
    private LocalDateTime timestamp;
}
