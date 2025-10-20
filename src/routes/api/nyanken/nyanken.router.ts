import { Router } from "express";
import * as nyankanController from "./nyankenController";
import * as notImplementedController from "../notImplementedController";

const nyankanRouter = Router();

nyankanRouter.post("/progress", nyankanController.progress);
nyankanRouter.post("/historyGet", nyankanController.historyGet);
nyankanRouter.post("/questlist", nyankanController.QuestList);
nyankanRouter.post("/start", nyankanController.nyankenStart);
nyankanRouter.post("/islandInfoGet", nyankanController.islandInfoGet);
nyankanRouter.post("/result", nyankanController.nyankenResult);

export default nyankanRouter;
