import express, {Request, Response} from "express";
import { check, validationResult } from "express-validator";
import User from "../models/user";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const router = express.Router();

router.post("/login", [
    check("email", "Email is requires").isEmail(),
    check("password", "Password is required").isLength({ min : 6})
], async( req: Request, res: Response) => {
     const errors = validationResult(req);
     if (!errors.isEmpty()) {
        return res.status(400).json({ message: errors.array() })
     }

     const { email, password } =  req.body;

     try {
        const user = await User.findOne({email});
        if(!user) {
            return res.status(400).json({ message: "Invalid login information. Please try again"})
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Your password is invalid. Please try again"})

        }

         const token = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET_KEY as string,
            { expiresIn: "1d" }
         );

         res.cookie("auth_token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 86400000
         });
         res.status(200).json({ userId: user._id }) //user._id is how it comes back from the mongodb document, and the reason we send back the user id is its convenience for the frontend or any client in case they need to do something on their side with the logged in user 

     } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Something went wrong!" })
     }
})

export default router;