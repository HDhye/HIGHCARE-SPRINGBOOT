package com.highright.highcare.approval.service;

import com.highright.highcare.approval.dto.*;
import com.highright.highcare.approval.entity.*;
import com.highright.highcare.approval.repository.*;
import com.highright.highcare.common.Criteria;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
@Slf4j
public class ApprovalExpService {

    private final ApvFormMainRepository apvFormMainRepository;
    private final ApvExpFormRepository apvExpFormRepository;
    private final ModelMapper modelMapper;

    @Autowired
    public ApprovalExpService(ModelMapper modelMapper,
                              ApvFormMainRepository apvFormMainRepository,
                              ApvExpFormRepository apvExpFormRepository
    ) {
        this.modelMapper = modelMapper;
        this.apvFormMainRepository = apvFormMainRepository;
        this.apvExpFormRepository = apvExpFormRepository;
    }

    /* 전자결재 - 지출 : exp1 지출결의서, exp4 출장경비정산서 */
    @Transactional
    public Boolean insertApvExpense(ApvFormWithLinesDTO apvFormWithLinesDTO) {
        log.info("[ApprovalService] insertApvExpense --------------- start ");

        try {
            ApvFormDTO apvFormDTO = apvFormWithLinesDTO.getApvFormDTO();
            List<ApvLineDTO> apvLineDTOs = apvFormWithLinesDTO.getApvLineDTOs();

            List<ApvExpFormDTO> apvExpFormDTO = apvFormDTO.getApvExpForms();
            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);

            // 1. apvForm만 등록하기
            ApvFormMain apvFormMain = modelMapper.map(apvFormDTO, ApvFormMain.class);

            ApvFormMain updateApvForm = apvFormMainRepository.save(apvFormMain);
            apvForm.setApvNo(updateApvForm.getApvNo());

            // 2. ApvLine 등록하기

            List<ApvLine> apvLineList = apvLineDTOs.stream().map(item -> modelMapper.map(item, ApvLine.class)).collect(Collectors.toList());

            apvLineList.forEach(item -> {
                item.setApvNo(updateApvForm.getApvNo());
            });
            updateApvForm.setApvLines(apvLineList);
            apvForm.setApvLines(apvLineList);

            // 3. ApvExpForm 등록하기

            List<ApvExpForm> expFormList = apvExpFormDTO.stream()
                    .map(item -> {
                        ApvExpForm expForm = modelMapper.map(item, ApvExpForm.class);
                        expForm.setApvNo(updateApvForm.getApvNo());
                        return expForm;
                    })
                    .collect(Collectors.toList());

            List<ApvExpForm> savedExpFormList = apvExpFormRepository.saveAll(expFormList);

            IntStream.range(0, apvForm.getApvExpForms().size())
                    .forEach(i -> {
                        ApvExpForm apvExpFormToUpdate = apvForm.getApvExpForms().get(i);
                        apvExpFormToUpdate.setItemsNo(savedExpFormList.get(i).getItemsNo());
                        apvExpFormToUpdate.setApvNo(savedExpFormList.get(i).getApvNo());
                        apvForm.getApvExpForms().set(i, apvExpFormToUpdate);
                    });

            log.info("[ApprovalService] insertApvExpense --------------- end ");
            return true;
        } catch (Exception e) {
            log.error("[ApprovalService] Error insertApvExpense : " + e.getMessage());
            return false;
        }
    }




//
//    /* 전자결재 - 지출 : exp1 지출결의서, exp4 출장경비정산서 */
//    @Transactional
//    public Object insertApvExpense(ApvFormWithLinesDTO apvFormWithLinesDTO) {
//        log.info("[ApprovalService] insertApvExpense --------------- start ");
//
//        try {
//            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);
//
//            if (apvFormDTO.getApvExpForms() != null) {
//                List<ApvExpForm> apvExpForms = new ArrayList<>();
//                for (ApvExpFormDTO expFormDTO : apvFormDTO.getApvExpForms()) {
//                    ApvExpForm apvExpForm = modelMapper.map(expFormDTO, ApvExpForm.class);
//                    apvExpForm.setApvNo(apvForm.getApvNo());
//                    apvExpForms.add(apvExpForm);
//                }
//                apvForm.setApvExpForms(apvExpForms);
//            }
//
//            approvalRepository.save(apvForm);
//
//            log.info("[ApprovalService] insertApvExpense --------------- end ");
//            return "기안 상신 성공";
//        } catch (Exception e){
//            log.error("[ApprovalService] Error insertApvForm : " + e.getMessage());
//            return "기안 상신 실패";
//        }
//    }
//
//    /* 전자결재 - 지출 : exp4 출장경비정산서 */
//    public List<ApvFormDTO> selectApvBusinessTripExp(int empNo, String title) {
//        log.info("[ApprovalService] selectWriteApvStatusApvList --------------- start ");
//
//        List<ApvForm> apvBusinessTripList = approvalRepository.findByEmpNoAndTitle(empNo, title);
//        System.out.println("empNo = " + empNo);
//        System.out.println("title = " + title);
//        System.out.println("apvBusinessTripList = " + apvBusinessTripList);
//        log.info("[ApprovalService] selectWriteApvStatusApvList --------------- end ");
//        return apvBusinessTripList.stream().map(apvForm -> modelMapper.map(apvForm, ApvFormDTO.class)).collect(Collectors.toList());
//    }
//
//
//
//    /* 전자결재 - 지출 : exp6 경조금 신청서 */
//    @Transactional
//    public Object insertApvFamilyEvent(ApvFormWithLinesDTO apvFormWithLinesDTO) {
//        log.info("[ApprovalService] insertApvFamilyEvent --------------- start ");
//
//        try {
//            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);
//
//            if (apvFormDTO.getApvFamilyEvents() != null) {
//                List<ApvFamilyEvent> apvFamilyEvents = new ArrayList<>();
//                for (ApvFamilyEventDTO familyEventDTO : apvFormDTO.getApvFamilyEvents()) {
//                    ApvFamilyEvent apvFamilyEvent = modelMapper.map(familyEventDTO, ApvFamilyEvent.class);
//                    apvFamilyEvent.setApvNo(apvForm.getApvNo());
//                    apvFamilyEvents.add(apvFamilyEvent);
//                }
//                apvForm.setApvFamilyEvents(apvFamilyEvents);
//            }
//
//            approvalRepository.save(apvForm);
//
//            log.info("[ApprovalService] insertApvFamilyEvent --------------- end ");
//            return "기안 상신 성공";
//        } catch (Exception e){
//            log.error("[ApprovalService] Error insertApvFamilyEvent : " + e.getMessage());
//            return "기안 상신 실패";
//        }
//    }
//
//    /* 전자결재 - 지출 : exp7 법인카드사용보고서 */
//    @Transactional
//    public Object insertApvCorpCard(ApvFormWithLinesDTO apvFormWithLinesDTO) {
//        log.info("[ApprovalService] insertApvCorpCard --------------- start ");
//
//        try {
//            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);
//
//            if (apvFormDTO.getApvCorpCards()!= null) {
//                List<ApvCorpCard> apvCorpCards = new ArrayList<>();
//                for (ApvCorpCardDTO corpCardDTO : apvFormDTO.getApvCorpCards()) {
//                    ApvCorpCard apvCorpCard = modelMapper.map(corpCardDTO, ApvCorpCard.class);
//                    apvCorpCard.setApvNo(apvForm.getApvNo());
//                    apvCorpCards.add(apvCorpCard);
//                }
//                apvForm.setApvCorpCards(apvCorpCards);
//            }
//
//            approvalRepository.save(apvForm);
//
//            log.info("[ApprovalService] insertApvCorpCard --------------- end ");
//            return "기안 상신 성공";
//        } catch (Exception e){
//            log.error("[ApprovalService] Error insertApvCorpCard : " + e.getMessage());
//            return "기안 상신 실패";
//        }
//    }
//
//
//
//
//
//    /* 전자결재 - 인사 : hrm1 연차신청서, hrm2 기타휴가신청서 */
//    @Transactional
//    public Object insertApvVacation(ApvFormWithLinesDTO apvFormWithLinesDTO) {
//
//        log.info("[ApprovalService] insertApvVacation --------------- start ");
//
//        try {
//            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);
//
//            if (apvFormDTO.getApvVacations() != null) {
//                List<ApvVacation> apvVacations = new ArrayList<>();
//                for (ApvVacationDTO vacationDTO : apvFormDTO.getApvVacations()) {
//                    ApvVacation apvVacation = modelMapper.map(vacationDTO, ApvVacation.class);
//                    apvVacation.setApvNo(apvForm.getApvNo());
//                    apvVacations.add(apvVacation);
//                }
//                apvForm.setApvVacations(apvVacations);
//            }
//
//            approvalRepository.save(apvForm);
//
//            log.info("[ApprovalService] insertApvVacation --------------- end ");
//            return "기안 상신 성공";
//        } catch (Exception e){
//            log.error("[ApprovalService] Error insertApvVacation : " + e.getMessage());
//            return "기안 상신 실패";
//        }
//    }
//
//    /* 전자결재 - 인사 : hrm3 서류발급신청서 */
//    @Transactional
//    public Object insertApvIssuance(ApvFormWithLinesDTO apvFormWithLinesDTO) {
//
//        log.info("[ApprovalService] insertApvIssuance --------------- start ");
//
//        try {
//            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);
//
//            if (apvFormDTO.getApvIssuances() != null) {
//                List<ApvIssuance> apvIssuances = new ArrayList<>();
//                for (ApvIssuanceDTO apvIssuanceDTO : apvFormDTO.getApvIssuances()) {
//                    ApvIssuance apvIssuance = modelMapper.map(apvIssuanceDTO, ApvIssuance.class);
//                    apvIssuance.setApvNo(apvForm.getApvNo());
//                    apvIssuances.add(apvIssuance);
//                }
//                apvForm.setApvIssuances(apvIssuances);
//            }
//
//            approvalRepository.save(apvForm);
//
//            log.info("[ApprovalService] insertApvIssuance --------------- end ");
//            return "기안 상신 성공";
//        } catch (Exception e){
//            log.error("[ApprovalService] Error insertApvIssuance : " + e.getMessage());
//            return "기안 상신 실패";
//        }
//    }


}

//    @Transactional
//    public Boolean insertApvBusinessTrip(ApvFormWithLinesDTO apvFormWithLinesDTO) {
//        log.info("[ApprovalService] insertApvBusinessTrip --------------- start ");
//        log.info("[ApprovalService] insertApvBusinessTrip {}", apvFormWithLinesDTO);
//
//        try {
//            ApvFormDTO apvFormDTO = apvFormWithLinesDTO.getApvFormDTO();
//            List<ApvLineDTO> apvLineDTOs = apvFormWithLinesDTO.getApvLineDTOs();
//
//            List<ApvBusinessTripDTO> apvBusinessTripDTO = apvFormDTO.getApvBusinessTrips();
//
//            System.out.println("1  apvFormDTO ======= " + apvFormDTO);
//            System.out.println("1  apvLineDTOs ======= " + apvLineDTOs);
//            System.out.println("1  meetingLogDTOs ======= " + apvBusinessTripDTO);
//            System.out.println("=========================================================");
//
//            ApvForm apvForm = modelMapper.map(apvFormDTO, ApvForm.class);
//
//            // 1. apvForm만 등록하기
//            ApvFormMain apvFormMain = modelMapper.map(apvFormDTO, ApvFormMain.class);
//            System.out.println("2-1  apvFormMain ======= " + apvFormMain);
//
//            ApvFormMain updateApvForm = apvFormMainRepository.save(apvFormMain);
//            System.out.println("/////// updateApvForm = " + updateApvForm);
//
//            System.out.println("updateApvForm.getApvNo() = " + updateApvForm.getApvNo());
//            System.out.println("2-1-2  apvFormMain  ======= " + apvFormMain);
//            apvForm.setApvNo(updateApvForm.getApvNo());
//            System.out.println("     2-1-  apvForm = " + apvForm);
//            System.out.println("=========================================================");
//
//
//            // 2. ApvLine 등록하기
//
//            List<ApvLine> apvLineList = apvLineDTOs.stream().map(item -> modelMapper.map(item, ApvLine.class)).collect(Collectors.toList());
//            System.out.println("2-2 apvLineList ======= " + apvLineList);
//
//            apvLineList.forEach(item -> {
//                item.setApvNo(updateApvForm.getApvNo());
//                System.out.println("item = " + item);
//            });
//            updateApvForm.setApvLines(apvLineList);
//
//            System.out.println("2-2-2 apvLineList ======= " + apvLineList);
//            List<ApvLine> savedApvLineList = apvLineRepository.saveAll(apvLineList);
//            System.out.println("2-2-2 savedApvLineList ======= " + savedApvLineList);
//
//            apvForm.setApvLines(apvLineList);
//            System.out.println("     2-2-  apvForm = " + apvForm);
//
//            System.out.println("=========================================================");
//
//
//            // 3. apvBusinessTrips 등록하기
//
//            List<ApvBusinessTrip> businessTripList = apvBusinessTripDTO.stream()
//                    .map(item -> {
//                        ApvBusinessTrip businessTrip = modelMapper.map(item, ApvBusinessTrip.class);
//                        businessTrip.setApvNo(updateApvForm.getApvNo());
//                        return businessTrip;
//                    })
//                    .collect(Collectors.toList());
//
//            System.out.println("2-3-1 meetingLogList ======= " + businessTripList);
//
//            List<ApvBusinessTrip> savedBusinessTripList = apvBusinessTripRepository.saveAll(businessTripList);
//            System.out.println("2-3-2 savedMeetingLogList ======= " + savedBusinessTripList);
//            System.out.println("     2-3-  pre apvForm = " + apvForm);
//
//            IntStream.range(0, apvForm.getApvBusinessTrips().size())
//                    .forEach(i -> {
//                        ApvBusinessTrip apvBusinessTripToUpdate = apvForm.getApvBusinessTrips().get(i);
//                        System.out.println("apvForm.getApvMeetingLogs().get(" + i + ") = " + apvBusinessTripToUpdate);
//
//                        apvBusinessTripToUpdate.setItemsNo(savedBusinessTripList.get(i).getItemsNo());
//                        apvBusinessTripToUpdate.setApvNo(savedBusinessTripList.get(i).getApvNo());
//
//                        apvForm.getApvBusinessTrips().set(i, apvBusinessTripToUpdate);
//                        System.out.println("apvMeetingLogToUpdate = " + apvForm.getApvBusinessTrips().get(i));
//                    });
//
//            System.out.println("     2-3-  apvForm = " + apvForm);
//
//            System.out.println("=========================================================");
//
//            log.info("[ApprovalService] insertApvMeetingLog --------------- end ");
//            return true;
//        } catch (Exception e) {
//            log.error("[ApprovalService] Error insertApvMeetingLog : " + e.getMessage());
//            return false;
//        }
//    }
