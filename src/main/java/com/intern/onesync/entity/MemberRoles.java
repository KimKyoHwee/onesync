package com.intern.onesync.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@Table
@Builder
public class MemberRoles {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_roles_id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "member_id")
    private Member member;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private Roles roles;
}
