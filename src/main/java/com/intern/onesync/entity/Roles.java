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
public class Roles {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Long id;

    @Column(name="role_name")
    private String name;

    @Column(name="role_description")
    private String description;

    @OneToMany(mappedBy = "roles")
    private List<MemberRoles> memberRolesList = new ArrayList<>();
}
