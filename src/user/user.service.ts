import { Injectable, Logger, NotFoundException,
    UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

/**
 * user.controller 의 API 에 적용할 메소드들의 로직을 갖는
 * 서비스 클래스
 * 패스워드 암호화 처리
 */
@Injectable()
export class UserService {
    //디버깅을 위해 로그 적용
    private readonly logger: Logger;

    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
    ) {
        //logger 인스턴스 생성
        this.logger = new Logger(UserService.name);
    }

    /**
     * createUser: existingEmail 값이 true 면 이미 가입된 이메일이 있음 오류 발생 메소드 종료
     * existingEmail 값이 false 면 DB 에 회원 등록. await createUser() 로 실행하면 User 를 반환 받음
     * @param {User} user
     * @return {Promise<User>} result 반환
     */
    async createUser(user: User): Promise<User> {
        this.logger.debug('createUser... ');
        const { email, password, name, birth, phone, addr } = user;
        const exist = await this.userRepository.findOne({ where: { email } });
        if (exist !== null) {
            this.logger.error('service: 이미 가입된 회원이 있습니다.');
            throw new Error('이미 가입된 회원이 있습니다.');
        }
        //패스워드 암호화 처리
        const hashedPassword = await bcrypt.hash(password, 10);
        //user 객체에 정보 담기
        const newUser: User = {
            email,
            password: hashedPassword,
            name,
            birth,
            phone,
            addr,
            createdDt: new Date(),
            updatedDt: null,
        };
        const result = await this.userRepository.save(newUser);
        this.logger.debug('새로운 회원을 생성 ' + result);
        return result;
    }




    /**
     * getUserByEmailPw: 이메일과 비밀번호가 일치하는 회원 조회
     * @param {string} email
     * @param {string} password
     * @return {Promise<User>} User 반환
     */
    //
    async getUserByEmailPw(email: string, password: string): Promise<User> {
        this.logger.debug('getUserByEmailPw... ');
        const user = await this.userRepository.findOne({ where: { email, password } });
        if (!user && user.email !== email && user.password !== password) {
            //DB 에서 email 과 password 중 하나라도 일치 하지 않을 경우 에러 발생
            throw new UnauthorizedException('입력한 정보와 일치하는 회원이 없습니다.');
        }
        this.logger.debug('조회된 회원 ' + user);
        return user;
    }
}
