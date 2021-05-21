package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/JxrezDev/IoTApi/config/db"
	"github.com/JxrezDev/IoTApi/model"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	collection, err := db.GetDBCollection()

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	var result model.User
	err = collection.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)

	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

			if err != nil {
				res.Error = "Error al encriptar su contraseña, Intente de nuevo"
				json.NewEncoder(w).Encode(res)
				return
			}
			user.Password = string(hash)

			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				res.Error = "Error mientras se creaba su usuario, intente de nuevo"
				json.NewEncoder(w).Encode(res)
				return
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": result.Username,
				"email":    result.Email,
			})

			tokenString, err := token.SignedString([]byte("secret"))

			if err != nil {
				res.Error = "Error mientras se generaba el Token, intente de nuevo"
				json.NewEncoder(w).Encode(res)
				return
			}

			res.Token = tokenString
			res.Result = "Registro Exitoso"
			json.NewEncoder(w).Encode(res)
			return
		}

		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Result = "Correo ya registrado!!"
	json.NewEncoder(w).Encode(res)
	return
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}

	collection, err := db.GetDBCollection()

	if err != nil {
		log.Fatal(err)
	}
	var result model.User
	var res model.ResponseResult

	err = collection.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)

	if err != nil {
		res.Error = "Correo de usuario invalido"
		json.NewEncoder(w).Encode(res)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
		res.Error = "Contraseña invalida"
		json.NewEncoder(w).Encode(res)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": result.Username,
		"email":    result.Email,
	})

	tokenString, err := token.SignedString([]byte("secret"))

	if err != nil {
		res.Error = "Error mientras se generaba el Token, intente de nuevo"
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Token = tokenString
	res.Result = "Login Exitoso"
	res.AuthVerification = result.AuthVerification

	json.NewEncoder(w).Encode(res)
}

func AuthVerification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte("secret"), nil
	})

	var res model.ResponseResult

	if err != nil {
		res.Error = "Error al cargar token"
		json.NewEncoder(w).Encode(res)
		return
	}

	var user model.User
	body, _ := ioutil.ReadAll(r.Body)
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}

	collection, err := db.GetDBCollection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		_, err = collection.UpdateOne(context.TODO(), bson.M{"email": claims["email"].(string)},
			bson.D{{"$set", bson.D{{"authVerification", user.AuthVerification}}}})

		println(claims["email"].(string))
		println(user.AuthVerification)
		if err != nil {
			res.Error = "Error mientras se actualizaba su registro, intente de nuevo"
			res.Result = err.Error()
			json.NewEncoder(w).Encode(res)
			return
		}

		res.AuthVerification = user.AuthVerification
		res.Result = "Actualizacon Exitosa"
		json.NewEncoder(w).Encode(res)
		return
	} else {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte("secret"), nil
	})

	var res model.ResponseResult

	if err != nil {
		res.Error = "Error al cargar token"
		json.NewEncoder(w).Encode(res)
		return
	}

	var result model.User
	var user model.User

	collection, err := db.GetDBCollection()
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		err = collection.FindOne(context.TODO(), bson.D{{"email", claims["email"].(string)}}).Decode(&user)
		if err != nil {
			res.Error = "Error al encontrar el usuario"
			json.NewEncoder(w).Encode(res)
			return
		}

		result.Username = user.Username
		result.Email = user.Email
		result.AuthVerification = user.AuthVerification
		json.NewEncoder(w).Encode(result)
		return
	} else {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
}

func BancaHandler(w http.ResponseWriter, r *http.Request) {

	u := url.URL{Scheme: "ws", Host: "143.198.109.195:5555", Path: "/"}
	c, _, _ := websocket.DefaultDialer.Dial(u.String(), nil)

	defer c.Close()

	w.Header().Set("Content-Type", "application/json")

	var banca model.Banca
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &banca)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	collection, err := db.GetDBIotCollection()

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	var result model.Banca
	err = collection.FindOne(context.TODO(), bson.D{{"idbanca", banca.IdBanca}}).Decode(&result)

	if err != nil {
		if err.Error() == "mongo: no documents in result" {

			_, err = collection.InsertOne(context.TODO(), banca)
			if err != nil {
				res.Error = "Error mientras se creaba su registro, intente de nuevo"
				json.NewEncoder(w).Encode(res)
				return
			}

			_ = c.WriteMessage(websocket.TextMessage, []byte("update"))
			log.Printf("Message sent: %s", "update")

			res.Result = "Registro Exitoso"
			json.NewEncoder(w).Encode(res)
			return
		}

		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	_, err = collection.UpdateOne(context.TODO(), bson.M{"idbanca": banca.IdBanca},
		bson.D{{"$set", bson.D{{"estado", banca.Estado}}}})
	if err != nil {
		res.Error = "Error mientras se actualizaba su registro, intente de nuevo"
		res.Result = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	_ = c.WriteMessage(websocket.TextMessage, []byte("update"))
	log.Printf("Message sent: %s", "update")

	res.Result = "Actualizacon Exitosa"
	json.NewEncoder(w).Encode(res)
}

func BancasHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	collection, err := db.GetDBIotCollection()

	var results []model.Banca
	var res model.ResponseResult
	findOptions := options.Find()
	cursor, err := collection.Find(context.TODO(), bson.D{{}}, findOptions)

	if err != nil {
		log.Fatal(err)
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	for cursor.Next(context.TODO()) {
		var elem model.Banca
		err := cursor.Decode(&elem)
		if err != nil {
			log.Fatal(err)
			res.Error = err.Error()
			json.NewEncoder(w).Encode(res)
			return
		}

		results = append(results, elem)
	}

	if err := cursor.Err(); err != nil {
		log.Fatal(err)
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	json.NewEncoder(w).Encode(results)
	return
}
