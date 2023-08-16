import { IsNotEmpty  , IsEmail,IsString ,Length} from "class-validator"



export class AuthDto {

@IsNotEmpty()
@IsEmail()
@IsString()
public email : string;


@IsNotEmpty()
@IsString()
@Length(3,20, {message: 'Password has to be at between 3 and 20 char'})
public password : string ;





}