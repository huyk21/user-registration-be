"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 10:
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(6);
const users_service_1 = __webpack_require__(11);
const jwt_1 = __webpack_require__(15);
const bcrypt = __webpack_require__(16);
let AuthService = class AuthService {
    constructor(usersService, jwtService) {
        this.usersService = usersService;
        this.jwtService = jwtService;
    }
    async register(username, email, password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await this.usersService.create(username, email, hashedPassword);
        return {
            message: 'User registered successfully',
            user: {
                username: newUser.username,
                email: newUser.email,
                id: newUser._id,
                createdAt: newUser.createdAt
            },
        };
    }
    async getProfile(usernameOrEmail) {
        const user = await this.usersService.findOneByUsernameOrEmail(usernameOrEmail, usernameOrEmail);
        if (!user) {
            throw new common_1.NotFoundException('User not found');
        }
        return {
            username: user.username,
            email: user.email,
            createdAt: user.createdAt,
        };
    }
    async signIn(usernameOrEmail, password) {
        const user = await this.usersService.findOneByUsernameOrEmail(usernameOrEmail, usernameOrEmail);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const payload = { sub: user._id, username: user.username };
        return {
            access_token: await this.jwtService.signAsync(payload),
        };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], AuthService);


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("31b2628a89675c62325f")
/******/ })();
/******/ 
/******/ }
;