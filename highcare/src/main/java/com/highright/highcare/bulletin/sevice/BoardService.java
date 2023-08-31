package com.highright.highcare.bulletin.sevice;

import com.highright.highcare.bulletin.dto.BulletinCategoriesDTO;
import com.highright.highcare.bulletin.dto.BulletinEmployeeDTO;
import com.highright.highcare.bulletin.dto.CommentDTO;
import com.highright.highcare.bulletin.entity.BulletinCategories;
import com.highright.highcare.bulletin.entity.BulletinEmployee;
import com.highright.highcare.bulletin.entity.Comment;
import com.highright.highcare.bulletin.repository.BoardRepository;
import com.highright.highcare.bulletin.repository.BulletinEmployeeRepository;
import com.highright.highcare.bulletin.repository.CommentRepository;
import com.highright.highcare.common.Criteria;
import net.minidev.json.JSONUtil;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import com.highright.highcare.bulletin.dto.BoardDTO;
import com.highright.highcare.bulletin.entity.Board;
import com.highright.highcare.bulletin.repository.BoardCategoryRepository;

import javax.transaction.Transactional;
import java.beans.Transient;
import java.sql.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class BoardService {

    private final BoardRepository boardRepository;
    private final BoardCategoryRepository boardCategoryRepository;
    private final ModelMapper modelMapper;

    private final CommentRepository commentRepository;

    private final BulletinEmployeeRepository bulletinEmployeeRepository;
    public BoardService(BoardRepository boardRepository,
                        ModelMapper modelMapper,
                        BoardCategoryRepository boardCategoryRepository,
                        CommentRepository commentRepository,
                        BulletinEmployeeRepository bulletinEmployeeRepository){
        this.boardRepository = boardRepository;
        this.modelMapper = modelMapper;
        this.boardCategoryRepository = boardCategoryRepository;
        this.commentRepository = commentRepository;
        this.bulletinEmployeeRepository = bulletinEmployeeRepository;
    }

    public List<BoardDTO> selectBoardList(){
        List<Board> boardList = boardRepository.findAll();
        return  boardList.stream()
                .map(board-> modelMapper.map(board, BoardDTO.class)).collect(Collectors.toList());
    }

    public List<BulletinCategoriesDTO> selectBoardTitle(){
        List<BulletinCategories> boardTitleList = boardCategoryRepository.findAll();
        return boardTitleList.stream()
                .map(boardTitle-> modelMapper.map(boardTitle, BulletinCategoriesDTO.class)).collect(Collectors.toList());
    }
    @Transactional
    public Object boardAdd(BulletinCategoriesDTO bulletinCategoriesDTO) {

        /* 게시판 중복 검사*/
        if(boardCategoryRepository.findByNameBoard(bulletinCategoriesDTO.getNameBoard())!= null){

            return null;
        }
        BulletinCategories category = modelMapper.map(bulletinCategoriesDTO, BulletinCategories.class);

        boardCategoryRepository.save(category);

        bulletinCategoriesDTO.setCategoryCode(category.getCategoryCode());

        return bulletinCategoriesDTO;
    }
    public int selectCommentTotal(String bulletinCode) {

        Board board = boardRepository.findById(Integer.valueOf(bulletinCode)).get();
        List<Comment> comments = commentRepository.findByBoard(board);
        return comments.size();
    }
    public int selectSearchTotal(int boardCategoryCode, String content) {
        List<Board> boardList;
        if(boardCategoryCode>2) {
            boardList = boardRepository.findByDeleteYnAndBulletinCategoriesAndTitleContains('N', boardCategoryRepository.findByCategoryCode(boardCategoryCode), content);
        }else{
            boardList = boardRepository.findByDeleteYnAndTitleContains('N', content);
        }

        return boardList.size();
    }

    public int selectBoardTotal(int boardCategoryCode) {
        List<Board> boardList;
        if(boardCategoryCode>2) {
            boardList = boardRepository.findByDeleteYnAndBulletinCategories('N', boardCategoryRepository.findByCategoryCode(boardCategoryCode));
        }else{
             boardList = boardRepository.findByDeleteYn('N');

        }

        return boardList.size();
    }
    public Object selectBoardAndCommentPaging(Criteria cri, String bulletinCode) {
        int index = cri.getPageNum() - 1;
        int count = cri.getAmount();
        int code = Integer.parseInt(bulletinCode);
        Pageable paging = PageRequest.of(index, count, Sort.by("modifiedDate").descending());
        Page<Comment> result = commentRepository.findByDeleteYnAndBoard('N',boardRepository.findById(code).get(),paging);
        List<Comment> commentList = (List<Comment>)result.getContent();
        return commentList.stream().map(comment -> modelMapper.map(comment, CommentDTO.class)).collect(Collectors.toList());
    }
    public Object selectBoardListWithPagingSearch(Criteria cri, int boardCategoryCode, String content) {
        int index = cri.getPageNum() - 1;
        int count = cri.getAmount();
        Pageable paging = PageRequest.of(index, count, Sort.by("bulletinCode").descending());

        Page<Board> result;
        if(boardCategoryCode>2) {
            result = boardRepository.findByDeleteYnAndBulletinCategoriesAndTitleContains('N', boardCategoryRepository.findByCategoryCode(boardCategoryCode),content,paging);

        } else if (boardCategoryCode == 2 ) {
            paging = PageRequest.of(index, count, Sort.by("views").descending());
            result = boardRepository.findByDeleteYnAndTitleContains('N',content,paging);
        } else{
            paging = PageRequest.of(index, count, Sort.by("modifiedDate").descending());
            result = boardRepository.findByDeleteYnAndTitleContains('N',content,paging);
        }


        List<Board> boardList = (List<Board>)result.getContent();
        System.out.println(boardList.stream().map(board -> modelMapper.map(board, BoardDTO.class)).collect(Collectors.toList()));
        return boardList.stream().map(board -> modelMapper.map(board, BoardDTO.class)).collect(Collectors.toList());
    }
    public Object selectBoardListWithPaging(Criteria cri, int boardCategoryCode) {
        int index = cri.getPageNum() - 1;
        int count = cri.getAmount();
        Pageable paging = PageRequest.of(index, count, Sort.by("bulletinCode").descending());

        Page<Board> result;
        if(boardCategoryCode>2) {
            result = boardRepository.findByDeleteYnAndBulletinCategories('N', boardCategoryRepository.findByCategoryCode(boardCategoryCode),paging);

        } else if (boardCategoryCode == 2 ) {
            paging = PageRequest.of(index, count, Sort.by("views").descending());
            result = boardRepository.findByDeleteYn('N',paging);
        } else{
            paging = PageRequest.of(index, count, Sort.by("modifiedDate").descending());
            result = boardRepository.findByDeleteYn('N',paging);
        }


        List<Board> boardList = (List<Board>)result.getContent();
        System.out.println(boardList.stream().map(board -> modelMapper.map(board, BoardDTO.class)).collect(Collectors.toList()));
        return boardList.stream().map(board -> modelMapper.map(board, BoardDTO.class)).collect(Collectors.toList());
    }
    @Transactional
    public Object selectBoard(int code) {
        Board board = boardRepository.findById(code).get();
        board.setViews(board.getViews()+1);
        BoardDTO boardDTO = modelMapper.map(board, BoardDTO.class);

        List<Comment> comment = commentRepository.findByBoard(board);
        List<CommentDTO> commentList = comment.stream().map(comment1 -> modelMapper.map(comment1, CommentDTO.class)).collect(Collectors.toList());
        boardDTO.setCommentCnt(commentList.size());
        return boardDTO;
    }
    @Transactional
    public Object insertBoard(BoardDTO boardDTO) {
        System.out.println("boardDTO get empNo : " + boardDTO.getEmpNo());
            BulletinCategoriesDTO bulletinCategoriesDTO = modelMapper.map(boardCategoryRepository.findByCategoryCode(boardDTO.getCategoryCode()), BulletinCategoriesDTO.class);
        boardDTO.setBulletinCategories(bulletinCategoriesDTO);

        java.util.Date utilDate = new java.util.Date();
        long currentMilliseconds = utilDate.getTime();
        java.sql.Date sqlDate = new java.sql.Date(currentMilliseconds);

        boardDTO.setCreationDate(sqlDate);
        boardDTO.setModifiedDate(sqlDate);
        boardDTO.setDeleteYn('N');

        BulletinEmployeeDTO bulletinEmployeeDTO = modelMapper.map(bulletinEmployeeRepository.findById(boardDTO.getEmpNo()).get(), BulletinEmployeeDTO.class);

        boardDTO.setBulletinEmployee(bulletinEmployeeDTO);
        Board board = modelMapper.map(boardDTO, Board.class);
        boardRepository.save(board);

        return 1;
    }
    @Transactional
    public Object insertComment(BoardDTO boardDTO) {
        java.util.Date utilDate = new java.util.Date();
        long currentMilliseconds = utilDate.getTime();
        java.sql.Date sqlDate = new java.sql.Date(currentMilliseconds);

        CommentDTO commentDTO = new CommentDTO();
        commentDTO.setCommentContent(boardDTO.getContent());
        commentDTO.setBoard(boardDTO);
        commentDTO.setCreationDate(sqlDate);
        commentDTO.setModifiedDate(sqlDate);
        commentDTO.setDeleteYn('N');
        BulletinEmployeeDTO bulletinEmployeeDTO = modelMapper.map(bulletinEmployeeRepository.findById(boardDTO.getEmpNo()).get(), BulletinEmployeeDTO.class);
        commentDTO.setBulletinEmployee(bulletinEmployeeDTO);
        Comment comment = modelMapper.map(commentDTO, Comment.class);
        commentRepository.save(comment);

        return 1;

    }
    @Transactional
    public Object updateBoard(BoardDTO boardDTO) {
        java.util.Date utilDate = new java.util.Date();
        long currentMilliseconds = utilDate.getTime();
        java.sql.Date sqlDate = new java.sql.Date(currentMilliseconds);

        String title = boardDTO.getTitle();
        String content = boardDTO.getContent();
        Board board = boardRepository.findById(boardDTO.getBulletinCode()).get();

        board.setContent(content);
        board.setTitle(title);
        board.setModifiedDate(sqlDate);



        return 1;

    }
    @Transactional
    public Object deleteBoard(BoardDTO boardDTO) {
        java.util.Date utilDate = new java.util.Date();
        long currentMilliseconds = utilDate.getTime();
        java.sql.Date sqlDate = new java.sql.Date(currentMilliseconds);
        Board board = boardRepository.findById(boardDTO.getBulletinCode()).get();
        board.setDeleteYn('Y');
        board.setModifiedDate(sqlDate);

        return 1;

    }



}
