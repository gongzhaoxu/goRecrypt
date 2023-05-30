package curve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

// 该文件提供椭圆曲线、椭圆曲线的运算函数
var CURVE = elliptic.P256()
var P = CURVE.Params().P
var N = CURVE.Params().N

type CurvePoint = ecdsa.PublicKey

// 创建点
func PointScalarAdd(a, b *CurvePoint) *CurvePoint {
	x, y := CURVE.Add(a.X, a.Y, b.X, b.Y)
	return &CurvePoint{CURVE, x, y}
}

// 点乘
func PointScalarMul(a *CurvePoint, k *big.Int) *CurvePoint {
	x, y := a.ScalarMult(a.X, a.Y, k.Bytes())
	return &CurvePoint{CURVE, x, y}
}

// 点倍基
func BigIntMulBase(k *big.Int) *CurvePoint {
	x, y := CURVE.ScalarBaseMult(k.Bytes())
	return &CurvePoint{CURVE, x, y}
}

// 点序列化为字节流
func PointToBytes(point *CurvePoint) (res []byte) {
	res = elliptic.Marshal(CURVE, point.X, point.Y)
	return
}
