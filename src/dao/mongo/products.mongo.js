import productModel from "../models/product.model.js"

export default class Products {
    constructor() {
    }

    getProduct = async(pid) =>{
        let product = await productModel.findOne({_id: pid})
        return product
    }

    deleteProduct = async(pid) =>{
        let eliminado = await productModel.deleteOne({ _id: pid })
        return eliminado
    }

    updateProduct = async(pid, productToReplace) => {
        let actualizado = await productModel.updateOne({_id: pid}, productToReplace)
        return actualizado
    }
    
    createProduct = async(newProduct) => {
        let nuevoProducto = await productModel.create(newProduct)
        return nuevoProducto
    }

}