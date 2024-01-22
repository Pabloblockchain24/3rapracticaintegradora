import jwt from "jsonwebtoken"
import config from "../config/config.js"
import {usersService} from "../repositories/index.js"

const verifyToken = async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) return res.status(401).json({ message: "Autorización denegada" });

    jwt.verify(token, config.TOKEN_SECRET, async(err,user) => {
        if (err) return res.status(403).json({ message: "Token invalidos" })   
        req.user = await usersService.getById(user.id) 
        next()
    });
};


export const adminAuth = async(req,res,next) => {
    try {
        await verifyToken(req, res, next);
        if(req.user.role === "admin"){
            next();
        }else{
            return res.status(401).json({message: "Autorizacion denegada"})
        }
    } catch (error) {
        return res.status(500).json({ message: "Error del servidor" });
    }
}

export const userAuth = async(req,res,next) => {
    try {
        await verifyToken(req, res, next);
        if(req.user.role === "user"){
            next();
        }else{
            return res.status(401).json({message: "Autorizacion denegada"})
        }
    } catch (error) {
        return res.status(500).json({ message: "Error del servidor" });
    }
}

export const premiumAuth = async (req,res,next) => {
    try {
        await verifyToken(req, res, async() =>{
            if(req.user.role === "premium"){
                next()
            }else{
                return res.status(401).json({message: "Autorizacion denegada en middleware ADMINORPREMIUM"})
            }
        });
    } catch (error) {
        return res.status(500).json({ message: "Error del servidor" });
    }
}

export const adminOrPremiumAuth = async (req,res,next) => {
    try {
        await verifyToken(req, res, async() =>{
            if(req.user.role === "premium" || req.user.role === "admin"){
                next()
            }else{
                return res.status(401).json({message: "Autorizacion denegada; no es admin ni usuario premium"})
            }
        });
    } catch (error) {
        return res.status(500).json({ message: "Error del servidor" });
    }
}

export const adminOrPremiumOrUserAuth = async (req,res,next) => {
    try {
        await verifyToken(req, res, async() =>{
            if(req.user.role === "premium" || req.user.role === "admin" || req.user.role === "user"){
                next()
            }else{
                return res.status(401).json({message: "Autorizacion denegada; no es admin ni usuario premium ni usuario"})
            }
        });
    } catch (error) {
        return res.status(500).json({ message: "Error del servidor" });
    }
}