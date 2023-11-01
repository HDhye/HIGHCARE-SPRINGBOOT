package com.highright.highcare.admin.repository;

import com.highright.highcare.admin.entity.ADMAuthAccount;
import com.highright.highcare.admin.entity.ADMAuthAccountId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

public interface ADMAuthAccountRepository extends JpaRepository<ADMAuthAccount, ADMAuthAccountId> {

    List<ADMAuthAccount> findById_Id(String id);

    @Modifying(clearAutomatically = true)      // 영속성 컨텍스트 최신화 
    @Query("DELETE FROM ADMAuthAccount a WHERE a.id.id = :id AND a.id.authCode = :authCode") // ADMAuthAccount 엔티티 클래스 이름으로 수정
    void deleteByIdAndAuthCode(@Param("id") String id, @Param("authCode") String authCode);


    Optional<ADMAuthAccount> findById_IdAndId_AuthCode(String id, String authCode);

    @Modifying(clearAutomatically = true)      // 영속성 컨텍스트 최신화
    @Query("delete from AUTHAuthAccount a where a.id = :id")
    void deleteByMemberId(@Param("id") String id);


}
