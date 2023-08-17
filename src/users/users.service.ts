import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { Request } from 'express';
@Injectable()
export class UsersService {

    constructor(private prisma: PrismaService) {

    }



    async getMyUser(id: string, req: Request) {

        const user = await this.prisma.user.findUnique({
            where: { id }

        })

        if (!user) {
            throw new HttpException("Not Found user", HttpStatus.NOT_FOUND)
        }


        const decodedUser = req.user as { id: string, email: string }


        if(user.id !== decodedUser.id){
            throw new HttpException("",HttpStatus.FORBIDDEN)
        }

        delete user.hasdedPassword

        return user

    }

    async getUsers() {
        return await this.prisma.user.findMany({
            select: { id: true, email: true }
        });
    }

}
