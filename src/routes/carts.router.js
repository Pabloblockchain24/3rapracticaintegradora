import { Router } from "express";
const router = Router()
import { deleteCart, deleteProductInCart, updateCart, updateProductInCart, postProductInCart, getAllCarts, postCart, purchaseCart } from "../controllers/cart.controller.js"
import { adminOrPremiumOrUserAuth } from "../middlewares/validate.js";

// obtengo todos los carritos en endpoint "/api/carts"
router.get("/", getAllCarts)

// Creo nuevos carritos vacios en "/api/carts"
router.post("/", postCart)

// Posteo nuevos productos al carrito en en "/api/carts/:cid/products/:pid"
router.post("/:cid/products/:pid", adminOrPremiumOrUserAuth, postProductInCart)

//edito carrito pasado por params en endpoint "/api/carts/:cid"
router.put("/:cid", updateCart)

//edito productos del carrito pasado por params en endpoint "/api/carts/:cid/products/:pid"
router.put("/:cid/products/:pid", updateProductInCart)

//elimino productos del carrito pasado por params en endpoint "/api/carts/:cid/products/:pid"
router.delete("/:cid/products/:pid", deleteProductInCart)

//vacio carrito pasado por params en endpoint "api/carts/:cid"
router.delete("/:cid", deleteCart)

// nueva ruta para el sistema de tickets
router.post("/:cid/purchase", purchaseCart)
export default router