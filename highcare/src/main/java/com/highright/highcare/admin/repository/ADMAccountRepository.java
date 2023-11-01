package com.highright.highcare.admin.repository;

import com.highright.highcare.admin.entity.ADMAccount;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface ADMAccountRepository extends JpaRepository<ADMAccount, String> {

    ADMAccount findByEmpNo(int empNo);

    
    @Query("SELECT DISTINCT a FROM ADMAccount a " +
            "LEFT JOIN  a.employee e " +
            "LEFT JOIN  a.roleList r " +
            "LEFT JOIN  a.accessManager c " +
            "ORDER BY CASE WHEN r.authCode = 'ROLE_PRE_USER' THEN 0 ELSE 1 END, a.empNo ASC")
    Page<ADMAccount> findAllOrderByPreUserOrder(Pageable pageable);

    ADMAccount findBymemberId(String id);

    Page<ADMAccount> findAllByOrderByAccessManager_RegistDateDesc(Pageable pageable);


    Page<ADMAccount> findByAccessManager_RegistDateBetweenOrderByAccessManager_RegistDateDesc(LocalDateTime start, LocalDateTime end, Pageable pageable);

    @Query(value = "SELECT a.* FROM TBL_ACCOUNT a " +
            "JOIN TBL_EMPLOYEE e ON a.EMP_NO = e.EMP_NO " +
            "WHERE e.EMP_NAME LIKE '%' || :keyword || '%'", nativeQuery = true)
    Page<ADMAccount> findByEmployee_NameContaining(@Param("keyword") String keyword, Pageable pageable);

}
