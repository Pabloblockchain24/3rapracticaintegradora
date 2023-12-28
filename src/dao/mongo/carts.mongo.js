import cartModel from "../models/cart.model.js"

export default class Carts {
    constructor() {
    }

    getCart = async(cid) =>{
        try {
            let cartFound = await cartModel.findOne({_id: cid}).populate("products.product")
            return cartFound
        } catch (error) {
            console.log(error)
            return null
        }
    }

    createNewCart = async() =>{
        try {
            let newCart = await cartModel.create({})
            return newCart
        } catch (error) {
            console.log(error)
            return null
        }
    }

    updateCart = async(cid,newCart) => {
        try {
            let cartUpdated = await cartModel.updateOne({_id: cid}, newCart)
            return cartUpdated
        } catch (error) {
            console.log(error)
            return null
        }
    }


}

