# [1.11.0](https://github.com/adlerre/mod_repudiator/compare/v1.10.0...v1.11.0) (2025-11-20)


### Features

* implement country based reputation ([973a87c](https://github.com/adlerre/mod_repudiator/commit/973a87cddd1a434ff18a8e40e6214ecc1f2c4a99))

# [1.10.0](https://github.com/adlerre/mod_repudiator/compare/v1.9.0...v1.10.0) (2025-06-19)


### Features

* add changelog to rpm ([#9](https://github.com/adlerre/mod_repudiator/issues/9)) ([05147b6](https://github.com/adlerre/mod_repudiator/commit/05147b6343b56e34d8ce438ba86d37c51a5ad0cf))

# [1.9.0](https://github.com/adlerre/mod_repudiator/compare/v1.8.1...v1.9.0) (2025-05-19)


### Bug Fixes

* ignore case and allow also on/off ([e1506e7](https://github.com/adlerre/mod_repudiator/commit/e1506e7ba974275416359636245c08ba580880ae))
* update readme ([d16c32d](https://github.com/adlerre/mod_repudiator/commit/d16c32dac2d0ad6c81ccd56d53b9296f41e5de85))


### Features

* use apache's internal functions to parse config ([5a2ea30](https://github.com/adlerre/mod_repudiator/commit/5a2ea30e0df950e325c5ccd86a75feb38421c1bf))

## [1.8.1](https://github.com/adlerre/mod_repudiator/compare/v1.8.0...v1.8.1) (2025-05-19)


### Bug Fixes

* fixing segmentation fault ([2d187c6](https://github.com/adlerre/mod_repudiator/commit/2d187c6977a71634cd16592b2944feec49cb04e5))

# [1.8.0](https://github.com/adlerre/mod_repudiator/compare/v1.7.1...v1.8.0) (2025-05-18)


### Features

* output version on startup ([#8](https://github.com/adlerre/mod_repudiator/issues/8)) ([645424c](https://github.com/adlerre/mod_repudiator/commit/645424ce8b24347145ed33805e2380aaf76f2386))

## [1.7.1](https://github.com/adlerre/mod_repudiator/compare/v1.7.0...v1.7.1) (2025-05-17)


### Bug Fixes

* it was too much ([f25d2cb](https://github.com/adlerre/mod_repudiator/commit/f25d2cb603d0777ff11ecc19251d4c1a4dab8165))

# [1.7.0](https://github.com/adlerre/mod_repudiator/compare/v1.6.0...v1.7.0) (2025-05-17)


### Features

* add more bad user-agents ([00f7680](https://github.com/adlerre/mod_repudiator/commit/00f7680268c4708123601133d2bf9247122cecc3))

# [1.6.0](https://github.com/adlerre/mod_repudiator/compare/v1.5.1...v1.6.0) (2025-05-15)


### Features

* option to append raw URI to redirect URL ([a54a5ee](https://github.com/adlerre/mod_repudiator/commit/a54a5eee2880951985f62f74a21c1a5149f5d297))

## [1.5.1](https://github.com/adlerre/mod_repudiator/compare/v1.5.0...v1.5.1) (2025-05-12)


### Bug Fixes

* unset reputation header to prevent merging ([ff37bd2](https://github.com/adlerre/mod_repudiator/commit/ff37bd20006c2e2ec15f4473c6be0e42348de924))

# [1.5.0](https://github.com/adlerre/mod_repudiator/compare/v1.4.1...v1.5.0) (2025-05-11)


### Bug Fixes

* rename to what it is and fix handling ([df25485](https://github.com/adlerre/mod_repudiator/commit/df254856481d4233e91a1a9ab4451062da1a9d6c))


### Features

* add delay feature for evil mode ([10bca72](https://github.com/adlerre/mod_repudiator/commit/10bca72ad3b3e4827a25e7df55c70f6b974b0005))

## [1.4.1](https://github.com/adlerre/mod_repudiator/compare/v1.4.0...v1.4.1) (2025-05-10)


### Bug Fixes

* free memory ([4fbbbfc](https://github.com/adlerre/mod_repudiator/commit/4fbbbfc1ae5cb9fe85e439fcbb808be5dd107078))

# [1.4.0](https://github.com/adlerre/mod_repudiator/compare/v1.3.1...v1.4.0) (2025-05-10)


### Bug Fixes

* add some more URI examples ([f7f1456](https://github.com/adlerre/mod_repudiator/commit/f7f145663b4f34a030a778e91febb019b5081424))


### Features

* add evil redirect URL ([f52d1d4](https://github.com/adlerre/mod_repudiator/commit/f52d1d411608db67a2a1457d92c32a8e42fe3cee))

## [1.3.1](https://github.com/adlerre/mod_repudiator/compare/v1.3.0...v1.3.1) (2025-05-10)


### Bug Fixes

* randomize redirect ([e393e69](https://github.com/adlerre/mod_repudiator/commit/e393e69b4e944cc20f01ce7ae96c4ca655560f84))

# [1.3.0](https://github.com/adlerre/mod_repudiator/compare/v1.2.0...v1.3.0) (2025-05-09)


### Features

* EVIL MODE ([4c877ae](https://github.com/adlerre/mod_repudiator/commit/4c877ae50d47f697a09bc17db9d9c647e284b2b8))

# [1.2.0](https://github.com/adlerre/mod_repudiator/compare/v1.1.0...v1.2.0) (2025-05-09)


### Bug Fixes

* fixing set of netmask if ASN DB isn't configured ([29dd724](https://github.com/adlerre/mod_repudiator/commit/29dd7247f5aaed46d8fed4b9ffee10f7cbfe826f))


### Features

* add RC-based reputation scoring ([4ce463d](https://github.com/adlerre/mod_repudiator/commit/4ce463d5f15366f86550688d986b51bb05efe098))
* add X-Reputation header ([8c08aac](https://github.com/adlerre/mod_repudiator/commit/8c08aac661b756fa7020d0921e4d5a26feebbb45))

# [1.1.0](https://github.com/adlerre/mod_repudiator/compare/v1.0.3...v1.1.0) (2025-05-09)


### Bug Fixes

* make cleaner code ([34e2c85](https://github.com/adlerre/mod_repudiator/commit/34e2c85a006fdb62e68517f096e6f8ed6668f2c5))
* set mask also on error or if not found ([bbad26f](https://github.com/adlerre/mod_repudiator/commit/bbad26f256d922fbb26981b55483b42476143c3d))


### Features

* add fail2ban support ([bc50500](https://github.com/adlerre/mod_repudiator/commit/bc5050072bb5d63ec0c0da251e671a1092ef1ee2))

## [1.0.3](https://github.com/adlerre/mod_repudiator/compare/v1.0.2...v1.0.3) (2025-05-08)


### Bug Fixes

* release RPMs direct ([369461a](https://github.com/adlerre/mod_repudiator/commit/369461a2f19e494c1a1707d39517fe861fd64efb))
* snprintf instead of sprintf ([933721a](https://github.com/adlerre/mod_repudiator/commit/933721a5d985364951072faf46121cdeb1872ec6))
* use release version instead for tag ([b70fa3e](https://github.com/adlerre/mod_repudiator/commit/b70fa3ee4bdd4a6450e2608c4bc07962429e37ac))

## [1.0.2](https://github.com/adlerre/mod_repudiator/compare/v1.0.1...v1.0.2) (2025-05-08)


### Bug Fixes

* release workflow ([dc81f5b](https://github.com/adlerre/mod_repudiator/commit/dc81f5b479c2b8ae5896a6b051e985529b11805c))

## [1.0.1](https://github.com/adlerre/mod_repudiator/compare/v1.0.0...v1.0.1) (2025-05-08)


### Bug Fixes

* artifact release ([fb4ac5f](https://github.com/adlerre/mod_repudiator/commit/fb4ac5f75cc9c37c77bc8ee909231ccb14014a5a))

# 1.0.0 (2025-05-08)


### Bug Fixes

* add includes ([66eee26](https://github.com/adlerre/mod_repudiator/commit/66eee26a4bda92347c3d6be061d82a5505e68aee))
* add missing lib include ([4d4816f](https://github.com/adlerre/mod_repudiator/commit/4d4816fea92a999acef15b28c2ebdf1fc628b265))
* cleanup example config ([a9257eb](https://github.com/adlerre/mod_repudiator/commit/a9257eb424df5a6c4965f1af51e695f9a7251d6e))


### Features

* add release workflow ([2a66084](https://github.com/adlerre/mod_repudiator/commit/2a66084ad5ffc501c371ae9af88b44fbc81fa5b5))
* build RPM packages ([#3](https://github.com/adlerre/mod_repudiator/issues/3)) ([d871b7f](https://github.com/adlerre/mod_repudiator/commit/d871b7f686c988bd2394ee7b88e03d220b760981))
