#ifndef SNMPCLIENTEXCEPTION_H_
#define SNMPCLIENTEXCEPTION_H_
#include <iostream>

namespace tmx::utils {

class SNMPClientException : public std::exception
{
private:
    std::string message;

public:
    explicit SNMPClientException(const std::string& msg) : message(msg){};
    const char *what() const noexcept override 
    {
        return message.c_str();
    }
    ~SNMPClientException() override = default;
};

} // namespace tmx::utils

#endif /* SNMPCLIENTEXCEPTION_H_ */
