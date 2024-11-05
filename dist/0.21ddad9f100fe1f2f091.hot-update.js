"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 11:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersService = void 0;
const common_1 = __webpack_require__(6);
const mongoose_1 = __webpack_require__(12);
const mongoose_2 = __webpack_require__(13);
const users_schema_1 = __webpack_require__(15);
let UsersService = class UsersService {
    constructor(userModel) {
        this.userModel = userModel;
    }
    async findOneByUsernameOrEmail(username, email) {
        return this.userModel.findOne({
            $or: [{ username }, { email }],
        }).exec();
    }
    async create(username, email, password) {
        const existingUser = await this.findOneByUsernameOrEmail(username, email);
        if (existingUser) {
            throw new common_1.BadRequestException('Username or email already exists');
        }
        if (!username || !email || !password) {
            throw new common_1.BadRequestException('Username, email, and password are required');
        }
        const newUser = new this.userModel({
            username,
            email,
            password: password,
            createdAt: new Date(),
        });
        return newUser.save();
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)(users_schema_1.User.name)),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object])
], UsersService);


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("67f1c842a11df0e96695")
/******/ })();
/******/ 
/******/ }
;