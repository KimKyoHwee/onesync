package com.intern.onesync.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@Table
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    @Column(name = "member_username")
    private String username;

    @Column(name="member_email")
    private String email;

    @Column(name="member_password")
    private String password;

//    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "member_info", referencedColumnName = "info_id")
    private Info info;

    //    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "user_auth_code", referencedColumnName = "auth_code_id")
    private AuthorizationCodes authorizationCodes;

    @OneToMany(mappedBy = "member")
    private List<MemberRoles> memberRolesList = new ArrayList<>();
}
