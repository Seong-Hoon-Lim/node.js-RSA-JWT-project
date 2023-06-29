import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from "@nestjs/common";
import * as cookieParser from 'cookie-parser'
import * as path from 'path';
import * as dotenv from 'dotenv';

async function bootstrap() {

  const app = await NestFactory.create(AppModule);
  // 전역 파이프에 validationPipe 객체 추가
  app.useGlobalPipes(new ValidationPipe());
  // 쿠키 파서 설정(Request 객체에서 쿠키를 읽어오는 미들웨어 역할)
  app.use(cookieParser());
  await app.listen(8000);
}

bootstrap();
