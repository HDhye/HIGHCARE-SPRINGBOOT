package com.highright.highcare.pm.entity;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.sql.Date;
import java.util.List;

@Entity
@Table(name="TBL_CERTIFICATION")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Certification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "CER_NO")
    private Integer cerNo;

    @Column(name = "START_DATE")
    private Date startDate;

    @Column(name = "END_DATE")
    private Date endDate;

    @Column(name = "INSTITUTION")
    private String institution;

    @Column(name = "NAME")
    private String name;

//    @Column(name = "EMP_NO")
//    private int empNo;

//    @OneToMany(mappedBy = "certification")
//    private List<PmEmployee> employees;
    @ManyToOne
    @JoinColumn(name = "EMP_NO")
    private PmEmployee employees;
}
