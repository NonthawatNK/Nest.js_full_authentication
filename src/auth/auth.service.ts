import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';


@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService) { }



    async signup(dto: AuthDto) {
        const { email, password } = dto;

        const foundUser = await this.prisma.user.findUnique({ where: { email } })

        if (!foundUser) {
            const hasdedPassword = await this.hashPassword(password)
            await this.prisma.user.create({
                data: {
                    email: email,
                    hasdedPassword: hasdedPassword
                }
            })
        } else {
            throw new HttpException("Email alread exists", HttpStatus.BAD_REQUEST)
        }




        return { massage: "signup was succefull" }
    }


    async signin(dto: AuthDto) {

        const { email ,password} = dto

        const foundUser = await this.prisma.user.findUnique({ where: { email } })

        if (!foundUser) {
            throw new HttpException("Worng credentials", HttpStatus.BAD_REQUEST)
        }


        const isMath = await this.comparePasswords({
            password,
            hash : foundUser.hasdedPassword
        });


        if(!isMath){
            throw new HttpException("Worng credentials", HttpStatus.BAD_REQUEST)
        }

        //sing jwt and return to the user



        return ''
    }


    async signout() {


        return ''
    }




    async hashPassword(password: string) {

        const saltOrRounds = 10;
        return await bcrypt.hash(password, saltOrRounds);

    }

    async comparePasswords(args :{password : string , hash :string}){


     return await bcrypt.compare(args.password, args.hash);


    }


}
