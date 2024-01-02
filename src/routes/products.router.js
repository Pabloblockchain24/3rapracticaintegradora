import { Router } from "express";
const router = Router()
import { deleteProduct, updateProductById, postProduct, getProduct, getAllProducts} from "../controllers/product.controller.js"
import { adminAuth, premiumAuth, adminOrPremiumAuth } from "../middlewares/validate.js";


// obtengo todos los productos en endpoint "/api/products, puedo ordenar y filtran segun paginate"
router.get("/", getAllProducts)

// obtengo el producto solicitado en endpoint "/api/products/:pid"
router.get("/:pid", getProduct)

// posteo un nuevo producto en endpoint "/api/products"
router.post("/", premiumAuth, postProduct)

// actualizo un producto en endpoint "/api/products/:pid"
router.put("/:pid",adminAuth, updateProductById)

// borro un producto en endpoint "/api/products/:pid"
router.delete("/:pid",adminOrPremiumAuth, deleteProduct)

export default router