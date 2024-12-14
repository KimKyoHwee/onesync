package com.intern.onesync.service;

import com.intern.onesync.dto.BasicJoinDto;
import com.intern.onesync.entity.Member;
import com.intern.onesync.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;

    public Long saveMember(BasicJoinDto basicJoinDto){
        Member member=Member.from(basicJoinDto);
        //TODO: username겹치는거 확인 필요
        memberRepository.save(member);
        return member.getId();
    }
}
