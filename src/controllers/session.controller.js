import jwt from "jsonwebtoken"

import {usersService,cartsService} from "../repositories/index.js"

export const autenticar = async (req,res) =>{
    const { token } = req.cookies
    if (!token) {
        return res.json({ message: "NO EXISTE USUARIO AUTENTICADO" })
    }
    jwt.verify(token, "CODER_TOKEN", async (err, user) => {
        if (err) return res.status(403).json({ message: "Token invalido" })


        const userFound = await usersService.getById(user.id)


        const cartFound = await cartsService.getCartById(userFound.cart)

        res.render("profile.hbs", {
            first_name: userFound.first_name,
            last_name: userFound.last_name,
            email: userFound.email,
            age: userFound.age,
            cart: cartFound.products,
            role: userFound.role,
        })

    })
}