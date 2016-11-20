//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Test that header file is self-contained.
#include <beast/http/new_parser.hpp>

#include <beast/unit_test/suite.hpp>
#include <beast/test/string_istream.hpp>
#include <beast/test/string_ostream.hpp>
#include <beast/test/yield_to.hpp>
#include <beast/core/flat_streambuf.hpp>
#include <beast/core/streambuf.hpp>
#include <beast/http/string_body.hpp>

#if 0

/*

- Remove read() interfaces that work on a header only.

*/
A. Caller wants to skip body YES/NO (e.g. HEAD response)
    p.set_option(body_skip{true});
    p.set_option(body_skip{false}); // default
    f_ |= flagSkipBody
    
B. Caller wants to pause the body YES/NO (implement Expect: 100-continue)
    p.set_option(body_pause{true});
    p.set_option(body_pause{false}); // default
    f_ |= flagPauseBody

C. Derived wants to pause the body YES/NO (construct from header)
    split(bool); // protected member
    f_ |= flagSplitParse
    
D. Message has a body YES/NO (Content-Length, Transfer-Encoding, Method, Upgrade)
    f_ |= flagNeedBody



template<class SyncReadStream, class DynamicBuffer, class Parser>
void
parse(SyncReadStream& stream, DynamicBuffer& dynabuf,
    Parser& parser, error_code& ec)
{
    for(;;)
    {
        auto used =
            parser.write(dynabuf.data(), ec);
        dynabuf.consume(used);
        if(ec)
            return;
        if(! parser.need_more())
            break;
        typename DynamicBuffer::mutable_buffers_type mb;
        try
        {
            mb = dynabuf.prepare(
                read_size_helper(dynabuf, 65536));
        }
        catch(std::length_error const&)
        {
            ec = error::buffer_overflow;
            return;
        }
        dynabuf.commit(stream.read_some(mb, ec));
        if(ec == boost::asio::error::eof)
        {
            // Caller will see eof on next read.
            ec = {};
            parser.write_eof(ec);
            if(ec)
                return;
            BOOST_ASSERT(! parser.need_more());
            break;
        }
        if(ec)
            return;
    }
}

/// Returns `true` if the parser requires more input
bool basic_parser::need_more() const

/// Returns `true` if we have received a complete header
bool basic_parser::have_header() const

/// Returns `true` if message semantics indicate a body, and skip_body is false
bool basic_parser::need_body() const
{
    BOOST_ASSERT(have_header());
    return ((f_ & (flagNeedBody | flagSkipBody)) == flagNeedBody);
}

/// Returns `true` if all parsing is complete
bool basic_parser:is_done() const

#endif

namespace beast {
namespace http {

struct str_body
{
    using value_type = std::string;

    class reader
    {
        std::size_t len_ = 0;
        value_type& body_;

    public:
        using mutable_buffers_type =
            boost::asio::mutable_buffers_1;

        template<bool isRequest, class Fields>
        explicit
        reader(message<isRequest, str_body, Fields>& msg)
            : body_(msg.body)
        {
        }

        void
        init(boost::optional<
            std::uint64_t> const& content_length,
                error_code& ec)
        {
            if(content_length)
            {
                if(*content_length >
                        (std::numeric_limits<std::size_t>::max)())
                    throw std::domain_error{"Content-Length overflow"};
                body_.reserve(*content_length);
            }
        }

        mutable_buffers_type
        prepare(std::size_t n, error_code& ec)
        {
            body_.resize(len_ + n);
            return {&body_[len_], n};
        }

        void
        commit(std::size_t n, error_code& ec)
        {
            if(body_.size() > len_ + n)
                body_.resize(len_ + n);
            len_ = body_.size();
        }

        void
        finish(error_code& ec)
        {
            body_.resize(len_);
        }
    };
};

//------------------------------------------------------------------------------

template<class SyncReadStream, class DynamicBuffer,
    bool isRequest, class Body, class Fields>
void
new_read(SyncReadStream& stream, DynamicBuffer& dynabuf,
    message<isRequest, Body, Fields>& msg, error_code& ec)
{
    new_parser<isRequest> parser{msg};
    for(;;)
    {
        auto used =
            parser.write(dynabuf.data(), ec);
        dynabuf.consume(used);
        if(ec)
            return;
        if(! parser.need_more())
            break;
        boost::optional<typename
            DynamicBuffer::mutable_buffers_type> mb;
        try
        {
            mb.emplace(dynabuf.prepare(
                read_size_helper(dynabuf, 65536)));
        }
        catch(std::length_error const&)
        {
            ec = error::buffer_overflow;
            return;
        }
        dynabuf.commit(stream.read_some(*mb, ec));
        if(ec == boost::asio::error::eof)
        {
            // Caller will see eof on next read.
            ec = {};
            parser.write_eof(ec);
            if(ec)
                return;
            BOOST_ASSERT(! parser.need_more());
            break;
        }
        if(ec)
            return;
    }
}

//------------------------------------------------------------------------------

class new_parser_test
    : public beast::unit_test::suite
    , public beast::test::enable_yield_to
{
public:
    template<bool isRequest, class Pred>
    void
    testMatrix(std::string const& s, Pred const& pred)
    {
        beast::test::string_istream ss{get_io_service(), s};
        error_code ec;
    #if 0
        streambuf dynabuf;
    #else
        flat_streambuf dynabuf;
        dynabuf.reserve(1024);
    #endif
        message<isRequest, string_body, fields> m;
        new_read(ss, dynabuf, m, ec);
        if(! BEAST_EXPECTS(! ec, ec.message()))
            return;
        pred(m);
    }

    void
    testRead()
    {
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "\r\n"
            "*******",
            [&](message<false, string_body, fields> const& m)
            {
                BEAST_EXPECTS(m.body == "*******",
                    "body='" + m.body + "'");
            }
        );
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "*****\r\n"
            "2;a;b=1;c=\"2\"\r\n"
            "--\r\n"
            "0;d;e=3;f=\"4\"\r\n"
            "Expires: never\r\n"
            "MD5-Fingerprint: -\r\n"
            "\r\n",
            [&](message<false, string_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*****--");
            }
        );
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "*****",
            [&](message<false, string_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*****");
            }
        );
        testMatrix<true>(
            "GET / HTTP/1.1\r\n"
            "User-Agent: test\r\n"
            "\r\n",
            [&](message<true, string_body, fields> const& m)
            {
            }
        );
        testMatrix<true>(
            "GET / HTTP/1.1\r\n"
            "User-Agent: test\r\n"
            "X: \t x \t \r\n"
            "\r\n",
            [&](message<true, string_body, fields> const& m)
            {
                BEAST_EXPECT(m.fields["X"] == "x");
            }
        );
    }

    struct transform
    {
        template<bool isRequest, class Fields>
        void
        operator()(
            header<isRequest, Fields>& msg, error_code& ec) const
        {
        }
    };

    void
    run() override
    {
        testRead();
    }
};

BEAST_DEFINE_TESTSUITE(new_parser,http,beast);

} // http
} // beast

