import { Body, Controller, Get, HttpCode, InternalServerErrorException,
    Logger, NotFoundException, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { UserService } from "./user.service";
import { User } from './user.entity';
import { AuthService } from "../auth/auth.service";

/**
 * 회원등록, 로그인/로그아웃
 * API 와 경로를 지정하는 컨트롤러 클래스
 *
 * '/user/signup' : POST - 회원 등록 처리
 * '/user/login' : POST - 로그인 처리
 */
@Controller('user')
export class UserController {
    //디버깅을 위해 로그 적용
    private readonly logger: Logger;
    constructor(
        private userService: UserService,
        private authService: AuthService
    ) {
        //logger 인스턴스 생성
        this.logger = new Logger(UserService.name);
    }

    /**
     * createUser: 회원 생성 API
     * @param {User} user - 생성할 회원 정보
     * @returns {Promise<User>} - 생성된 회원 정보
     */
    @Post('/signup')
    @HttpCode(201)
    async createUser(@Body() user: User): Promise<User> {
        this.logger.debug('controller: createUser... ');
        try {
            const createdUser = await this.userService.createUser(user);
            return createdUser;
        }
        catch (error) {
            this.logger.error('controller: 회원 등록 중 에러가 발생했습니다');
            throw new InternalServerErrorException('회원 등록 중 에러가 발생했습니다.', error);
        }
    }

    /**
     * login: 로그인 API
     * @param {string} email - 로그인 이메일
     * @param {string} password - 로그인 비밀번호
     * @returns {Promise<any>} - 로그인 결과
     */
    @Post('/login')
    async login(@Body('email') email: string, @Body('password') password: string, @Res() res: any): Promise<{accessToken: string}> {
        this.logger.debug('controller: login... ');
        try {
            // 입력 값이 없을 때
            if (!email || !password) {
                return res.status(400).send('이메일과 패스워드가 올바르지 않습니다');
            }
            const validatedUser = await this.authService.validateUser(email, password);
            const accessToken = this.authService.generateAccessToken(validatedUser);
            this.logger.debug('controller: accessToken' + accessToken);
            return res.sendStatus(200, accessToken);
        } catch (error) {
            return res.status(401).send(error.message);
        }
    }

    /**
     * logout: 로그아웃 API
     * @param {any} req - 요청 객체
     * @param {any} res - 응답 객체
     * @returns {Promise<any>} - 로그아웃 결과
     */
    @Post('/logout')
    async logout(@Req() req: any, @Res() res: any): Promise<any> {
        try {
            res.clearCookie('access_token');
            return res.sendStatus(200);
        } catch (error) {
            return res.sendStatus(500);
        }
    }
}
