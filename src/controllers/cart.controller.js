import { usersService, cartsService, productsService, ticketsService } from "../repositories/index.js"

export const deleteCart = async (req, res) => {
    let cid = req.params.cid
    const carrito = await cartsService.getCartById(cid)
    if (!carrito) {
        return res.send({ message: "carrito no encontrado" })
    }
    carrito.products = []
    let result = await carrito.save()
    res.send({ result: "success", payload: result })
}

export const deleteProductInCart = async (req, res) => {
    let { cid, pid } = req.params
    const carrito = await cartsService.getCartById(cid)
    if (!carrito) return res.send({ message: "carrito no encontrado" })

    try {
        const producto = carrito.products.findIndex(producto => producto.product.equals(pid))
        if (producto === -1) return res.send({ message: "producto no encontrado" })
        carrito.products.splice(producto, 1)
        let result = await carrito.save()
        res.send({ result: "success", payload: result })
    } catch (error) {
        console.log(error)
    }
}

export const updateProductInCart = async (req, res) => {
    let cid = req.params.cid
    let pid = req.params.pid
    let cantidadNueva = req.body.quantity

    const carrito = await cartsService.getCartById(cid)
    if (!carrito) return res.send({ message: "carrito no encontrado" })

    try {
        const producto = carrito.products.findIndex(producto => producto.product.equals(pid))
        if (producto === -1) {
            return res.send({ message: "producto no encontrado" })
        }
        carrito.products[producto].quantity = cantidadNueva
        let result = await carrito.save()
        res.send({ result: "success", payload: result })
    } catch (error) {
        console.log(error)
    }
}

export const updateCart = async (req, res) => {
    let cid = req.params.cid
    const carrito = await cartsService.getCartById(cid)
    if (!carrito) return res.send({ message: "carrito no encontrado" })

    carrito.products = [{
        product: "654a239b02e55dcb17b58278",
        quantity: 1
    },
    {
        product: "654a23a902e55dcb17b5827a",
        quantity: 2
    },
    ]
    let result = await carrito.save()
    res.send({ result: "success", payload: result })
}

export const postProductInCart = async (req, res) => {
    let { cid, pid } = req.params

    const carrito = await cartsService.getCartById(cid)
    if (!carrito) return res.send({ message: "carrito no encontrado" })

    const producto = await productsService.getProductById(pid)
    if (!producto) return res.send({ message: "producto no encontrado" })


    if (req.user.role === "premium") {
        if (producto.owner.equals(req.user._id)) {
            const productoEnCarrito = carrito.products.find((prod) => prod.product.equals(producto._id))
            if (!productoEnCarrito) {
                const nuevoProduct = { product: producto._id, quantity: 1 }
                carrito.products.push(nuevoProduct)
            } else {
                productoEnCarrito.quantity++
            }
            let result = await carrito.save();
            res.send({ result: "success", payload: result })
        } else {
            res.status(404).send({ status: "error", message: "Producto no pertenece al usuario premium autenticado" });
        }

    } else {
        try {
            const productoEnCarrito = carrito.products.find((prod) => prod.product.equals(producto._id))
            if (!productoEnCarrito) {
                const nuevoProduct = { product: producto._id, quantity: 1 }
                carrito.products.push(nuevoProduct)
            } else {
                productoEnCarrito.quantity++
            }
            let result = await carrito.save();
            res.send({ result: "success", payload: result })
        } catch (error) {
            console.log(error)
        }
    }





}

export const postCart = async (req, res) => {
    let result = await cartsService.createCart()
    res.send({ result: "success", payload: result })
}

export const getAllCarts = async (req, res) => {
    let result = await cartsService.getAllCarts()
    res.send({ result: "success", payload: result })
}

export const purchaseCart = async (req, res) => {
    let purchase = []
    let notPurchase = []
    let amountPurchase = 0

    let cid = req.params.cid
    let carrito = await cartsService.getCartById(cid)
    if (!carrito) {
        return res.send({ message: "carrito no encontrado" })
    }
    for (const item of carrito.products) {
        const productFound = await productsService.getProductById(item.product._id)

        if (productFound.stock >= item.quantity) {
            purchase.push({ producto: item.product._id, cantidad: item.quantity })
            amountPurchase += (item.product.precio * item.quantity)
            productFound.stock = productFound.stock - item.quantity
            await productsService.updateProductById(item.product._id, productFound)
        } else {
            notPurchase.push({ producto: item.product._id })
        }
    }

    // aqui creo un nuevo carrito y lo recorro, revisando si el item esta guardado en purchase (lo que significa que no debe persistir en el carrito),
    // solo quedara lo que no pudo ser comprado, luego actualizo los products del carrito y lo guardo
    let newCart = []
    for (const item of carrito.products) {
        if (!purchase.some(purchase => purchase.producto === item.product._id)) {
            newCart.push(item)
        }
    }
    carrito.products = newCart
    await cartsService.updateCartById(cid, carrito)


    if (purchase) {
        const userFound = await usersService.getUserByCartId(cid)
        const timestamp = Date.now()
        const random = Math.random()

        let newTicket = {
            code: `${timestamp}-${random}`,
            purchase_datetime: timestamp,
            amount: amountPurchase,
            purcharser: userFound.email
        }
        await ticketsService.createTicket(newTicket)

        if (notPurchase.length >= 1) {
            res.send({ message: `Su ticket es: ${JSON.stringify(newTicket)} y quedaron sin comprar por falta de stock: ${JSON.stringify(notPurchase)}` })
            return
        }
        res.send({ result: "success", payload: newTicket })

    }
}

