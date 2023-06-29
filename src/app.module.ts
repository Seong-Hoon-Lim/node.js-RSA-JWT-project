/**
 * 애플리케이션의 모듈 클래스를 정의
 * SQLite DB 설정
 */

import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { User } from './user/user.entity';

@Module({
    imports: [
        //sqlite 설정 메소드
        TypeOrmModule.forRoot({
            type: 'sqlite',
            database: "api-jwt.sqlite",
            entities: [User],
            synchronize: true,
            logging: true,
        }),
        UserModule,
        AuthModule,
        ConfigModule.forRoot(), // .env 파일 로드
        JwtModule.registerAsync({
            useFactory: () => ({
                privateKey: process.env.JWT_PRIVATE_KEY,
                publicKey: process.env.JWT_PUBLIC_KEY,
                signOptions: {
                    expiresIn: process.env.JWT_EXPIRES_IN,
                },
            }),
        }),
    ],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
