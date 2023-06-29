/**
 * DB 테이블과 1:1 매칭 되는 필드를 가지고 있는 클래스
 * 회원 정보를 가지고 있음
 */

import {Column, Entity, PrimaryGeneratedColumn} from 'typeorm';

@Entity()
export class User {
    @PrimaryGeneratedColumn('increment')
    uid?: number;   //PK 설정

    @Column({unique: true})
    email: string;  //UNIQUE 설정 NOT NULL

    @Column()
    password: string;   //NOT NULL

    @Column()
    name: string;   //NOT NULL

    @Column()
    birth: string;  //NOT NULL

    @Column()
    phone: string;  //NOT NULL

    @Column()
    addr: string;   //NOT NULL

    @Column({ default: () => 'CURRENT_TIMESTAMP' })
    createdDt: Date = new Date();  //NOT NULL

    @Column({ nullable: true })
    updatedDt?: Date = new Date();  //NULL 허용


}
