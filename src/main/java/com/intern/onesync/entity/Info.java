package com.intern.onesync.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@Table
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Info {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "info_id")
    private Long id;
    
    //TODO: 사용자마다 저장할 정보 고려해야됨
    @Column
    private String info1;

    @Column
    private String info2;
}
