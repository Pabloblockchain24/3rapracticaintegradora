import jwt from "jsonwebtoken"
import config from "../config/config.js"
import {usersService} from "../repositories/index.js"

export const adminAuth = (req,res,next) => {
    const {token} = req.cookies
    if (!token) return res.status(401).json({message: "Autorizacion denegada"})

    jwt.verify(token,config.TOKEN_SECRET, async(err,user) => {
        if (err) return res.status(403).json({ message: "Token invalidos" })
        const userFound = await usersService.getById(user.id)

        if(userFound.role==="admin"){
            req.user=user
            next()
        }else{
            return res.status(401).json({message: "Autorizacion denegada"})
        }
    })
}

export const userAuth = (req,res,next) => {
    const {token} = req.cookies
    if (!token) return res.status(401).json({message: "Autorizacion denegada"})

    jwt.verify(token,config.TOKEN_SECRET, async(err,user) => {
        if (err) return res.status(403).json({ message: "Token invalidos" })
        const userFound = await usersService.getById(user.id)
        if(userFound.role==="user"){
            req.user=user
            next()
        }else{
            return res.status(401).json({message: "Autorizacion denegada"})
        }
    })
}
