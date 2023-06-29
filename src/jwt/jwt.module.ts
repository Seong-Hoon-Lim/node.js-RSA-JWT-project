import { Module } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';

@Module({
    imports: [JwtModule.register({
        secret: process.env.JWT_PUBLIC_KEY,
            signOptions: {
                expiresIn: process.env.JWT_EXPIRES_IN,
            },
        }),
    ],
    providers: [JwtService],
})
export class JwtConfigModule {}
