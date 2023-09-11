package com.highright.highcare.admin.controller;


import com.highright.highcare.admin.dto.RequestMemberDTO;
import com.highright.highcare.admin.dto.UpdateAccountDTO;
import com.highright.highcare.admin.service.AdminService;
import com.highright.highcare.common.ResponseDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequestMapping("/api/admin")
@RestController
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    @GetMapping("/member")
    public ResponseEntity<ResponseDTO> selectMember(@RequestParam String empNo){
        log.info("================= empNo ===== {}" , empNo);
        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "사원 조회", adminService.selectMember(Integer.valueOf(empNo))));
    }

    // 인서트 회원신청
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    @PostMapping("/memberjoin")
    public ResponseEntity<ResponseDTO> insertAccount(@RequestBody RequestMemberDTO requestMemberDTO){
        log.info("[AdminController] insertAccount requestMemberDTO===={}", requestMemberDTO);

        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "회원 등록 신청", adminService.insertAccount(requestMemberDTO)));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/memberlist")
    public ResponseEntity<ResponseDTO> selectAccountList(){

        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "전체 회원 조회", adminService.selectAccountList()));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @PutMapping("/member/{id}")
    public ResponseEntity<ResponseDTO> updateAccount(@PathVariable String id, @RequestBody UpdateAccountDTO updateAccountDTO){

        log.info("[AdminController] updateAccount id ===={}", id);
        log.info("[AdminController] updateAccount updateAccountDTO===={}",updateAccountDTO);


        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "회원 계정상태 수정", adminService.updateAccount(id, updateAccountDTO)));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @DeleteMapping("/member/{id}")
    public ResponseEntity<ResponseDTO> updateAccount(@PathVariable String id){
        log.info("[AdminController] updateAccount id===={}", id);


        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "회원 삭제(탈퇴)", adminService.deleteAccount(id)));
    }


    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    @GetMapping("/jobs")
    public ResponseEntity<ResponseDTO> selectJobList(){
        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "직급 조회", adminService.selectJobList()));
    }

    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    @GetMapping("/department")
    public ResponseEntity<ResponseDTO> selectDepartmentList(){
        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "부서 조회", adminService.selectDepartmentsList()));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/menugroup")
    public ResponseEntity<ResponseDTO> selectMenuGroupList(){
        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "메뉴그룹 조회", adminService.selectMenuGroupList()));
    }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/managers")
    public ResponseEntity<ResponseDTO> selectMenuManagers(){
        return ResponseEntity.ok().body(new ResponseDTO(HttpStatus.OK.value(),
                "매니저 조회", adminService.selectMenuManagers()));
    }




}
