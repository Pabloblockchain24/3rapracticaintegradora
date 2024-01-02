import {productsService} from "../repositories/index.js"
import productModel from "../dao/models/product.model.js"

export const updateProductById = async (req, res) => {
    let { pid } = req.params
    let productToReplace = req.body
    if (!productToReplace.nombre || !productToReplace.descripcion || !productToReplace.precio || !productToReplace.category || !productToReplace.stock) {
        res.send({ status: "error", error: "no hay datos en parametros" })
    }
    let result = await productsService.updateProductById(pid, productToReplace)
    res.send({ result: "success", payload: result })
}

export const deleteProduct = async (req, res) => {
    let pid = req.params.pid

    if (req.user.role === "premium"){
        let productFound = await productsService.getProductById(pid)
        if (productFound.owner.equals(req.user._id)){
            let result = await productsService.deleteProductById(pid)
            res.send({ result: "success", payload: result })
        }else{
            res.status(404).send({ status: "error", message: "Producto no pertenece al usuario premium autenticado" });
        }
    }else{
        await productsService.deleteProductById(pid)
        res.send({ result: "success", payload: result })
    } 

}

export const postProduct = async (req, res) => {
    let { nombre, descripcion, category, precio, stock } = req.body
    if (!nombre || !descripcion || !category || !precio || !stock) {
        return res.send({ status: "error", error: "faltan datos" })
    }else{
        const newProduct = {nombre, descripcion, category, precio, stock, owner:req.user._id}
        await productsService.postProduct(newProduct)
        res.status(400).send({ result: "success", payload: newProduct })
    }

}

export const getProduct = async (req, res) => {
    const productId = req.params.pid
    let producto = await productsService.getProductById(productId)
    try {
        if (producto) {
            res.send({ result: "success", payload: producto })
        } else {
            res.status(404).send({ status: "error", message: "Producto no encontrado" });
        }
    } catch (error) {
        console.log(error)
    }
}

export const getAllProducts = async (req, res) => {
    const page = req.query.page || 1
    const limit = req.query.limit || 3
    const sortDirection = req.query.sortDirection || ''
    const category = req.query.category || ""

    const sortOptions = {};
    if (sortDirection === 'asc') {
        sortOptions.precio = 1;
    } else if (sortDirection === 'des') {
        sortOptions.precio = -1;
    }

    const filterOptions = {};
    if (category) {
        filterOptions.category = category;
    }

    productModel.paginate(filterOptions, { page, limit, sort: sortOptions }, (err, result) => {
        if (err) {
            return res.status(500).json({ result: 'error', payload: null });
        }
        const prevPage = result.page > 1 ? result.page - 1 : null;
        const nextPage = result.page < result.totalPages ? result.page + 1 : null;

        res.render("products.hbs", {
            url:req.originalUrl,
            productos: result.docs,
            totalPage: result.totalPages,
            prevPage,
            nextPage,
            hasPrevPage: result.hasPrevPage,
            hasNextPage: result.hasNextPage,
            prevLink: prevPage ? `/products?page=${prevPage}&limit=${limit}&sortDirection=${sortDirection}&category=${category}` : null,
            nextLink: nextPage ? `/products?page=${nextPage}&limit=${limit}&sortDirection=${sortDirection}&category=${category}` : null,
        },);
    })

}

