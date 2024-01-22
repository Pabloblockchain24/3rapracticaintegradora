import jwt from "jsonwebtoken"
import config from "./config/config.js"

export const createAccessToken = function(payload) {
    return new Promise((resolve, reject) => {
        jwt.sign(payload, config.TOKEN_SECRET, { expiresIn: "1d" }, (err, token) => {
            if (err) reject(err)
            resolve(token)
        })
    })
}

export const createResetToken = function(payload) {
    return new Promise((resolve, reject) => {
        jwt.sign(payload, config.TOKEN_SECRET, { expiresIn: "1h" }, (err, token) => {
            if (err) reject(err)
            resolve(token)
        })
    })
}

