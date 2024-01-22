import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "./schemas/user.schema";
import mongoose, { Model } from "mongoose";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        @InjectModel(User.name)
        private userModel: Model<User>
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET
        })
    }

    async validate(payload: { id: string }): Promise<User> {
        const { id } = payload;
        const isValidId = mongoose.isValidObjectId(id);

        if (!isValidId) {
            throw new UnauthorizedException('Invalid id!')
        }

        const user = await this.userModel.findById(id);

        if(!user) {
            throw new UnauthorizedException('Login first to access this endpoint!');
        }

        return user;
    }
}