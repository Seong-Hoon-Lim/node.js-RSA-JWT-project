import { Injectable, Logger } from '@nestjs/common';
import { User } from "../user/user.entity";
import { Repository } from 'typeorm';
import { JwtService } from "@nestjs/jwt";
import { UserService } from "../user/user.service";
import {InjectRepository} from "@nestjs/typeorm";
import { SignOptions, VerifyOptions } from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import * as process from "process";
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';

/**
 * JWT 인증을 활용한 로그인/로그아웃 처리 서비스 클래스
 */
@Injectable()
export class AuthService {
    //디버깅을 위해 로그 적용
    private readonly logger: Logger;

    private publicKey: string;
    private privateKey: string;

    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
    ) {
        //logger 인스턴스 생성
        this.logger = new Logger(UserService.name);

        this.publicKey = process.env.JWT_PUBLIC_KEY;
        this.privateKey = process.env.JWT_PRIVATE_KEY;
    }

    /**
     * generateAccessToken: 액세스 토큰을 생성.
     * @param {User} user
     * @return {string} 생성된 액세스 토큰
     */
    generateAccessToken(user: User): string {
        this.logger.debug('service: generateAccessToken... ');
        const header = {
            alg: 'RS256',
            typ: 'JWT',
        };
        const payload = {
            email: user.email,
            sub: user.uid,
            exp: Math.floor(Date.now() / 1000) + 3600, // 1시간 유효기간
        };
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
        const privateKey = crypto.createPrivateKey({
            key: this.privateKey,
            format: 'pem',
        });
        this.logger.debug('service: encodedHeader 정보: ' + JSON.stringify(encodedHeader));
        this.logger.debug('service: encodedPayload 정보: ' + JSON.stringify(encodedPayload));
        this.logger.debug('service: privateKey 정보: ' + JSON.stringify(privateKey));
        const signOptions: SignOptions = {
            algorithm: 'RS256',
        };
        const token = this.jwtService.sign(payload, signOptions);
        if (!token) {
            this.logger.error('토큰 생성에 실패 했습니다.');
        } else {
            this.logger.debug('service: 토큰이 발행되었습니다.');
        }
        return token;
    }

    /**
     * validateUser: 회원의 이메일과 비밀번호가 일치 여부 검증. 회원이 존재하고
     * 파라미터로 전달 된 이메일 과 패스워드 모두 일치 해야만 일치하는 회원 조회
     * @param {string} email
     * @param {string} password
     * @return {Promise<User>} User 반환
     */
    async validateUser(email: string, password: string): Promise<User> {
        this.logger.debug('service: validateUser... ');
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) {
            this.logger.error('service: 입력한 정보와 일치하는 회원이 없습니다');
            throw new Error('입력한 정보와 일치하는 회원이 없습니다.');
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            this.logger.error('service: 입력한 정보와 일치하는 회원이 없습니다');
            throw new Error('입력한 정보와 일치하는 회원이 없습니다.');
        }

        // 회원 정보가 조회되면 서명을 생성하여 토큰을 발행합니다.
        const token = this.generateAccessToken(user);
        this.logger.debug('service: token 정보: ' + JSON.stringify(token));

        return user;
    }

    /**
     * verifyAccessToken: 액세스 토큰의 유효성을 검사합니다.
     * @param {string} token
     * @return {boolean} 토큰의 유효성 여부
     */
    verifyAccessToken(token: string): boolean {
        this.logger.debug('service: verifyAccessToken... ');
        try {
            this.logger.debug('service: 검증할 토큰: ' + token);
            jwt.verify(token, crypto.createPublicKey(this.publicKey), {
                algorithms: ['RS256'],
            });
            return true; // 토큰 유효성 검증 통과
        } catch (error) {
            this.logger.error('토큰 검증에 실패 했습니다: ' + error.message);
            return false; // 토큰 유효성 검증 실패
        }
    }

    /**
     * setAccessTokenCookie: 액세스 토큰을 쿠키에 설정합니다.
     * @param {any} res
     * @param {string} token
     */
    setAccessTokenCookie(res: any, token: string): void {
        this.logger.debug('service: setAccessTokenCookie... ');
        res.cookie('access_token', token, {
            httpOnly: true,
        });
    }



    // /**
    //  * decodePublicKey: 공개키를 디코딩합니다.
    //  * @returns {string} 디코딩된 공개키
    //  */
    // decodePublicKey(): string {
    //     this.logger.debug('service: decodePublicKey... ');
    //     const formattedKey = this.publicKey.replace(/\n|\r/g, '').trim();
    //     const buffer = Buffer.from(formattedKey, 'base64');
    //     this.logger.debug('service: decodePublicKey: ' + buffer);
    //     return buffer.toString('utf-8');
    // }
    //
    // /**
    //  * decodePrivateKey: 암호키를 디코딩합니다.
    //  * @returns {string} 디코딩된 암호키
    //  */
    // decodePrivateKey(): string {
    //     this.logger.debug('service: decodePrivateKey... ');
    //     const formattedKey = this.privateKey.replace(/\n|\r/g, '').trim();
    //     const buffer = Buffer.from(formattedKey, 'base64');
    //     this.logger.debug('service: decodePrivateKey: ' + buffer);
    //     return buffer.toString('utf-8');
    // }
    //
    // /**
    //  * signWithPrivateKey: 비밀키를 사용하여 데이터를 서명합니다.
    //  * @param {string} data 서명할 데이터
    //  * @param {string} privateKey 비밀키
    //  * @returns {string} 서명된 데이터
    //  */
    // signWithPrivateKey(data: string, privateKey: string): string {
    //     this.logger.debug('service: signWithPrivateKey... ');
    //     const sign = crypto.createSign('RSA-SHA256');
    //     sign.write(data);
    //     sign.end();
    //     const signature = sign.sign(privateKey, 'base64');
    //     this.logger.debug('service: 생성된 signature: ' + signature);
    //     return signature;
    // }
    //
    // /**
    //  * generateSignature: 데이터를 공개키로 서명합니다.
    //  * @param {string} data 서명할 데이터
    //  * @returns {string} 서명된 데이터
    //  */
    // generateSignature(data: string): string {
    //     this.logger.debug('service: generateSignature... ');
    //     const decodedPrivateKey = this.decodePrivateKey();
    //     return this.signWithPrivateKey(data, decodedPrivateKey);
    // }

}
